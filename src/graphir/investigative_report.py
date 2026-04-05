"""Full investigative report generator — professional IR report format.

Generates a report in the structure a senior DFIR analyst would produce:
  1. Information Sources — what evidence was examined
  2. Incident Information — threat hunt details, system, user, date/time
  3. Assumptions and Limitations — what could and couldn't be analyzed
  4. Management Summary — major findings, verdict, key next steps
  5. Techniques and Methodology — how the investigation was conducted
  6. Findings — detailed findings with evidence, MACB timestamps, ATT&CK
  7. Conclusion — overall assessment
  8. Recommendations — operational / tactical / strategic
  9. Closing — investigation metadata, provenance, analyst notes

Rendered from graph state — the agent generates this autonomously.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_investigative_report(
    run_cypher,
    investigation_log,
    findings: list[dict],
    output_dir: str = "investigation-output",
) -> dict:
    """Generate a full investigative report from graph state."""
    lines = []

    ctx = _gather_context(run_cypher, investigation_log, findings)

    lines.append("# Incident Investigation Report")
    lines.append("")
    lines.append(f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Investigation ID:** {investigation_log.investigation_id}")
    lines.append(f"**Classification:** CONFIDENTIAL")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.extend(_section_1_sources(ctx))
    lines.extend(_section_2_incident_info(ctx))
    lines.extend(_section_3_assumptions(ctx))
    lines.extend(_section_4_management_summary(ctx))
    lines.extend(_section_5_methodology(ctx))
    lines.extend(_section_6_findings(ctx))
    lines.extend(_section_7_conclusion(ctx))
    lines.extend(_section_8_recommendations(ctx))
    lines.extend(_section_9_closing(ctx))
    lines.extend(_section_10_appendix(ctx, run_cypher))

    md_content = "\n".join(lines)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    md_path = out_path / "investigative-report.md"
    with open(md_path, "w") as f:
        f.write(md_content)

    return {
        "status": "ok",
        "markdown_path": str(md_path),
        "findings_count": len(ctx["active_findings"]),
    }


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

def _gather_context(run_cypher, log, findings) -> dict:
    ctx = {"findings_raw": findings}

    # Active findings (with hits)
    ctx["active_findings"] = [
        f for f in findings
        if isinstance(f, dict) and f.get("hit_count", 0) > 0
    ]

    # Nodes
    try:
        nodes = run_cypher("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS cnt ORDER BY cnt DESC")
        ctx["nodes"] = {r["label"]: r["cnt"] for r in nodes}
    except Exception:
        ctx["nodes"] = {}

    # Hosts
    try:
        hosts = run_cypher("MATCH (h:Host) WHERE h.hostname IS NOT NULL RETURN h.hostname ORDER BY h.hostname")
        ctx["hosts"] = [h["h.hostname"] for h in hosts if h["h.hostname"]]
    except Exception:
        ctx["hosts"] = []

    # Users
    try:
        ctx["users"] = run_cypher("""
            MATCH (u:User)-[r:LOGGED_ON]->(h:Host)
            RETURN u.name AS user, u.domain AS domain,
                   count(r) AS logons, collect(DISTINCT h.hostname) AS hosts
            ORDER BY logons DESC LIMIT 20
        """)
    except Exception:
        ctx["users"] = []

    # Time range
    try:
        tr = run_cypher("""
            MATCH ()-[r]->() WHERE r.timestamp IS NOT NULL
            RETURN min(r.timestamp) AS earliest, max(r.timestamp) AS latest
        """)
        if tr:
            ctx["earliest"] = str(tr[0].get("earliest", ""))[:19]
            ctx["latest"] = str(tr[0].get("latest", ""))[:19]
    except Exception:
        ctx["earliest"] = "unknown"
        ctx["latest"] = "unknown"

    # Provenance
    try:
        prov = run_cypher("""
            MATCH (n) WHERE NOT n:Host
            WITH count(*) AS total,
                 sum(CASE WHEN n._origin_tool IS NOT NULL THEN 1 ELSE 0 END) AS with_origin
            RETURN total, with_origin
        """)
        if prov:
            t, o = prov[0]["total"], prov[0]["with_origin"]
            ctx["prov_pct"] = f"{o/t*100:.1f}%" if t else "N/A"
        else:
            ctx["prov_pct"] = "N/A"
    except Exception:
        ctx["prov_pct"] = "N/A"

    # Corrections
    try:
        ctx["corrections"] = run_cypher("""
            MATCH (c:Correction) RETURN c.type AS type, c.reason AS reason,
            c.original_claim AS claim, c.corrected_by AS by ORDER BY c.timestamp
        """)
    except Exception:
        ctx["corrections"] = []

    # Enrichment
    try:
        ctx["enrichment"] = run_cypher("""
            MATCH (x:Executable)-[:ENRICHED_BY]->(ti:ThreatIntel)
            RETURN x.name AS executable, x.path AS path,
                   ti.family AS family, ti.detection_rate AS detections, ti.status AS status
            ORDER BY ti.detections DESC
        """)
    except Exception:
        ctx["enrichment"] = []

    # Log context
    summary = log.get_summary()
    ctx["elapsed_s"] = summary.get("elapsed_s", 0)
    ctx["verifications"] = summary.get("verifications", 0)
    ctx["log_corrections"] = summary.get("corrections", 0)
    ctx["investigation_id"] = log.investigation_id
    ctx["finding_details"] = [e for e in log.entries if e["entry_type"] == "finding"]

    # Multi-host?
    ctx["is_multi_host"] = len(ctx["hosts"]) > 1

    return ctx


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _section_1_sources(ctx) -> list[str]:
    lines = ["## 1. Information Sources", ""]
    lines.append("The following evidence sources were analyzed during this investigation:")
    lines.append("")
    lines.append("| Source Type | Count | Description |")
    lines.append("|------------|-------|-------------|")
    node_desc = {
        "Event": "Windows Event Log records (EVTX/EVT)",
        "File": "Filesystem entries with MACB timestamps",
        "Executable": "Binary execution evidence (prefetch, amcache, shimcache)",
        "Process": "Process execution instances (4688 events)",
        "User": "User accounts with logon history",
        "Host": "Investigated host systems",
        "Correction": "Investigation self-corrections",
        "ThreatIntel": "VirusTotal threat intelligence enrichments",
    }
    for label, count in ctx["nodes"].items():
        desc = node_desc.get(label, "")
        lines.append(f"| {label} | {count:,} | {desc} |")
    lines.append("")
    lines.append(f"**Data provenance coverage:** {ctx['prov_pct']} of entities traceable to raw source artifacts.")
    lines.append("")
    return lines


def _section_2_incident_info(ctx) -> list[str]:
    lines = ["## 2. Incident Information", ""]

    if ctx["is_multi_host"]:
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| **Type** | Multi-host investigation |")
        lines.append(f"| **Hosts** | {', '.join(ctx['hosts'][:10])} |")
        lines.append(f"| **Time range** | {ctx.get('earliest', '?')} to {ctx.get('latest', '?')} |")
        lines.append(f"| **Evidence scope** | {ctx['nodes'].get('Event', 0):,} events across {len(ctx['hosts'])} hosts |")

        # Key users
        suspicious_users = [u for u in ctx["users"]
                           if u.get("user", "") not in ("SYSTEM", "ANONYMOUS LOGON", "unknown")
                           and not u.get("user", "").endswith("$")]
        if suspicious_users:
            user_names = [u["user"] for u in suspicious_users[:5]]
            lines.append(f"| **Key accounts** | {', '.join(user_names)} |")
    else:
        host = ctx["hosts"][0] if ctx["hosts"] else "Unknown"
        lines.append("| Property | Value |")
        lines.append("|----------|-------|")
        lines.append(f"| **Host** | {host} |")
        lines.append(f"| **Time range** | {ctx.get('earliest', '?')} to {ctx.get('latest', '?')} |")
        lines.append(f"| **Evidence scope** | {ctx['nodes'].get('Event', 0):,} events |")

    lines.append("")
    lines.append("### User Activity Summary")
    lines.append("")
    lines.append("| User | Domain | Logons | Hosts Accessed |")
    lines.append("|------|--------|--------|----------------|")
    for u in ctx["users"][:10]:
        user = u.get("user", "?")
        domain = u.get("domain", "")
        logons = u.get("logons", 0)
        hosts = ", ".join([h for h in u.get("hosts", []) if h][:3])
        lines.append(f"| {user} | {domain} | {logons:,} | {hosts} |")
    lines.append("")
    return lines


def _section_3_assumptions(ctx) -> list[str]:
    lines = ["## 3. Assumptions and Limitations", ""]
    lines.append("### Assumptions")
    lines.append("")
    lines.append("- System clocks were synchronized and timestamps are reliable")
    lines.append("- The forensic image was acquired without modification to the original evidence")
    lines.append("- Plaso timeline output accurately represents the artifacts present on disk")
    lines.append("")
    lines.append("### Limitations")
    lines.append("")
    lines.append("- **No memory analysis** — process injection, unlinked processes, and in-memory-only artifacts are not visible")
    lines.append("- **No network captures** — C2 communications, data exfiltration volumes, and lateral movement protocols cannot be directly observed")
    lines.append("- **Command-line data may be absent** — if process auditing (Event ID 4688 with command-line logging) was not enabled, process arguments are unknown")
    lines.append("- **Verification constraints** — findings classified as INFERENCE have artifact evidence (prefetch, shimcache) but lack the EVTX process chain data required for structural CONFIRMATION")
    lines.append(f"- **Provenance** — {ctx['prov_pct']} of graph entities have complete origin traceability. Entities created by MERGE operations (Host, User) may lack individual origin metadata.")
    lines.append("")
    return lines


def _section_4_management_summary(ctx) -> list[str]:
    lines = ["## 4. Management Summary", ""]

    finding_count = len(ctx["active_findings"])
    malware = [e for e in ctx["enrichment"] if e.get("status") == "found" and e.get("detections")]
    corrections = ctx["corrections"]

    # Check for strong indicators from agent findings (PsExec, RATs, AV bypass, etc.)
    agent_findings_text = " ".join(
        e.get("detail", "") for e in ctx["finding_details"]
    ).lower()
    has_strong_indicators = any(term in agent_findings_text for term in [
        "psexec", "lateral movement", "remote shell", "backdoor", "rat",
        "mimikatz", "credential dump", "av bypass", "avbypass",
        "masquerad", "timestomp", "recycle bin",
    ])

    if malware:
        verdict = "COMPROMISE CONFIRMED"
        lines.append(f"**Verdict: {verdict}**")
        lines.append("")
        lines.append(f"{len(malware)} executable(s) confirmed as malicious via VirusTotal threat intelligence. ")
    elif has_strong_indicators:
        verdict = "COMPROMISE INDICATED — HIGH CONFIDENCE"
        lines.append(f"**Verdict: {verdict}**")
        lines.append("")
        lines.append("Multiple strong indicators of compromise identified through artifact analysis. "
                     "Structural verification is limited by available evidence types (no EVTX process chains), "
                     "but the pattern of findings is consistent with active adversary operations. ")
    elif finding_count > 5:
        verdict = "SUSPICIOUS — FURTHER INVESTIGATION REQUIRED"
        lines.append(f"**Verdict: {verdict}**")
        lines.append("")
    elif finding_count > 0:
        verdict = "INDICATORS PRESENT — CONTEXT REQUIRED"
        lines.append(f"**Verdict: {verdict}**")
        lines.append("")
    else:
        verdict = "NO INDICATORS OF COMPROMISE DETECTED"
        lines.append(f"**Verdict: {verdict}**")
        lines.append("")

    # Major findings summary
    lines.append("**Major Findings:**")
    lines.append("")
    for f in ctx["active_findings"][:5]:
        tech = f.get("technique", "")
        desc = f.get("description", "")
        hits = f.get("hit_count", 0)
        lines.append(f"- [{tech}] {desc} ({hits} indicators)")

    # Agent findings
    for entry in ctx["finding_details"][:3]:
        conf = entry["data"].get("confidence", "")
        detail = entry.get("detail", "")[:80]
        lines.append(f"- [{conf}] {detail}")

    lines.append("")

    if corrections:
        lines.append(f"**Self-corrections:** {len(corrections)} finding(s) revised during investigation.")
        lines.append("")

    lines.append(f"**Investigation duration:** {ctx['elapsed_s']:.0f} seconds, {ctx['verifications']} structural verifications.")
    lines.append("")
    return lines


def _section_5_methodology(ctx) -> list[str]:
    lines = ["## 5. Techniques and Methodology", ""]
    lines.append("This investigation was conducted using graphir, a graph-based autonomous ")
    lines.append("incident response tool. The methodology follows these phases:")
    lines.append("")
    lines.append("1. **Evidence Ingestion** — Plaso JSON-L timelines ingested into a Neo4j graph database. ")
    lines.append("   Each artifact becomes a typed vertex (Process, Executable, File, Event, User, Host) ")
    lines.append("   with temporal edges preserving MACB timestamps and full provenance metadata.")
    lines.append("")
    lines.append("2. **Automated Triage** — 20 hunt patterns executed against the graph, detecting ")
    lines.append("   suspicious process chains, lateral movement, credential access, persistence, ")
    lines.append("   defense evasion, timestomping, and temporal anomalies.")
    lines.append("")
    lines.append("3. **Structural Verification** — Each finding verified via dual-path architecture ")
    lines.append("   (Parallel Sysplex principle). The LLM's inference is compared against independent ")
    lines.append("   structural graph predicates. Three confidence states: CONFIRMED, INFERENCE, ")
    lines.append("   INSUFFICIENT_EVIDENCE.")
    lines.append("")
    lines.append("4. **Threat Intelligence Enrichment** — Executable hashes queried against VirusTotal ")
    lines.append("   (hash-only, no file upload). Results stored as ThreatIntel graph nodes with ")
    lines.append("   ENRICHED_BY edges for traceability.")
    lines.append("")
    lines.append("5. **Self-Correction** — Findings that fail structural verification or are determined ")
    lines.append("   to be false positives are recorded as Correction nodes in the graph. The agent ")
    lines.append("   checks for existing corrections before re-asserting claims.")
    lines.append("")
    lines.append("All tools are exposed via the Model Context Protocol (MCP). The agent has read-only ")
    lines.append("access to the investigation graph (enforced at database protocol level).")
    lines.append("")
    return lines


def _section_6_findings(ctx) -> list[str]:
    lines = ["## 6. Findings", ""]
    lines.append("*Confidence: **CONFIRMED** = structurally verified | **INFERENCE** = artifact evidence, ")
    lines.append("not structurally confirmed | **INSUFFICIENT_EVIDENCE** = claim not supported by graph*")
    lines.append("")

    num = 0

    # VT enrichment findings
    malware = [e for e in ctx["enrichment"] if e.get("status") == "found" and e.get("detections")]
    if malware:
        num += 1
        lines.append(f"### 6.{num} Confirmed Malware (VirusTotal Intelligence)")
        lines.append("")
        lines.append("| Executable | Family | Detections | Path |")
        lines.append("|------------|--------|------------|------|")
        for m in malware:
            path = _format_cell("path", m.get("path", ""))
            lines.append(f"| {m.get('executable', '?')} | {m.get('family', '?')} | {m.get('detections', '?')} | {path} |")
        lines.append("")

    # Hunt findings
    for f in ctx["active_findings"]:
        num += 1
        desc = f.get("description", "")
        tactic = f.get("tactic", "")
        technique = f.get("technique", "")
        results = f.get("results", [])

        lines.append(f"### 6.{num} {desc}")
        lines.append("")
        lines.append(f"- **ATT&CK:** {tactic} / {technique}")
        lines.append(f"- **Indicators:** {f.get('hit_count', 0)}")
        if f.get("truncated"):
            lines.append(f"- *Results capped at {f.get('showing', 10)}. Additional matches exist in the graph.*")
        lines.append("")

        if results and isinstance(results[0], dict):
            keys = list(results[0].keys())
            if len(keys) <= 8:
                lines.append("| " + " | ".join(keys) + " |")
                lines.append("| " + " | ".join(["---"] * len(keys)) + " |")
                for r in results[:10]:
                    vals = [_format_cell(k, r.get(k, "")) for k in keys]
                    lines.append("| " + " | ".join(vals) + " |")
            else:
                for r in results[:10]:
                    parts = [f"**{k}:** {_format_cell(k, v)}" for k, v in r.items() if v]
                    lines.append(f"- {' | '.join(parts[:4])}")
            lines.append("")

    # Agent-discovered findings
    for entry in ctx["finding_details"]:
        detail = entry.get("detail", "")
        confidence = entry["data"].get("confidence", "")
        if any(detail[:30].lower() in str(f.get("description", "")).lower()
               for f in ctx["active_findings"]):
            continue
        num += 1
        lines.append(f"### 6.{num} {detail}")
        lines.append("")
        lines.append(f"- **Confidence:** {confidence}")
        lines.append(f"- **Source:** Agent investigation (structural verification)")
        lines.append("")

    # Corrections
    if ctx["corrections"]:
        num += 1
        lines.append(f"### 6.{num} Self-Corrections")
        lines.append("")
        for c in ctx["corrections"]:
            lines.append(f"- **[{c.get('type', '?')}]** {c.get('claim', '')}")
            lines.append(f"  - Reason: {c.get('reason', '')}")
            lines.append(f"  - Corrected by: {c.get('by', '?')}")
        lines.append("")

    return lines


def _section_7_conclusion(ctx) -> list[str]:
    lines = ["## 7. Conclusion", ""]

    malware = [e for e in ctx["enrichment"] if e.get("status") == "found" and e.get("detections")]
    finding_count = len(ctx["active_findings"])

    if malware:
        lines.append("This investigation has confirmed the presence of malware on the examined system(s). ")
        lines.append("The identified executables have been verified against VirusTotal threat intelligence. ")
        lines.append("Immediate containment and remediation actions are recommended as outlined in Section 8.")
    elif finding_count > 5:
        lines.append("Multiple suspicious indicators were identified during this investigation. ")
        lines.append("While structural confirmation is limited by available evidence types, the ")
        lines.append("pattern of findings is consistent with unauthorized activity. Further ")
        lines.append("investigation with additional evidence sources is recommended.")
    elif finding_count > 0:
        lines.append("A limited number of indicators were identified. These require contextual ")
        lines.append("analysis by a human analyst to determine whether they represent genuine ")
        lines.append("threats or legitimate administrative activity.")
    else:
        lines.append("No significant indicators of compromise were identified in the examined evidence. ")
        lines.append("This does not exclude the possibility of compromise through vectors not covered ")
        lines.append("by the available evidence (see Limitations in Section 3).")

    lines.append("")
    return lines


def _section_8_recommendations(ctx) -> list[str]:
    lines = ["## 8. Recommendations", ""]

    malware = [e for e in ctx["enrichment"] if e.get("status") == "found" and e.get("detections")]
    has_lateral = any(f.get("hunt") == "lateral_movement_logons"
                      for f in ctx["active_findings"])

    lines.append("### 8.1 Operational — Immediate (Today)")
    lines.append("")
    if malware:
        lines.append("- **ISOLATE** affected host(s) from the network")
        lines.append("- **BLOCK** identified malicious hashes at endpoint protection layer")
        lines.append("- **PRESERVE** evidence — do not reimage until forensic collection is complete")
        lines.append("- **RESET** credentials for all accounts on affected hosts")
    elif has_lateral:
        lines.append("- **INVESTIGATE** source of lateral movement logons")
        lines.append("- **REVIEW** accounts with Type 3/10 logons across multiple hosts")
        lines.append("- **RESET** credentials for suspicious accounts")
    else:
        lines.append("- No immediate containment required based on current findings")
    lines.append("")

    lines.append("### 8.2 Tactical — Near-term (This Week)")
    lines.append("")
    lines.append("- Deploy generated Sigma detection rules to SIEM")
    lines.append("- Review ATT&CK Navigator layer for coverage gaps")
    lines.append("- Enable enhanced process auditing (4688 + command-line)")
    lines.append("- Enable PowerShell script block logging")
    if malware:
        lines.append("- Scan all domain hosts for identified malicious hashes")
        lines.append("- Audit NETLOGON/SYSVOL shares on domain controllers")
    lines.append("")

    lines.append("### 8.3 Strategic — Long-term (This Quarter)")
    lines.append("")
    # Check if hosts include modern Windows (Win10+) or legacy (XP/Win7)
    hosts_str = " ".join(ctx["hosts"]).lower()
    has_legacy = any(x in hosts_str for x in ["xp", "win7", "2008", "2003"])
    has_modern = any(x in hosts_str for x in ["win10", "win11", "2016", "2019", "2022"])

    if has_legacy:
        lines.append("- **PRIORITY:** Migrate legacy systems (Windows XP/7/2008) to supported operating systems")
        lines.append("- Implement network segmentation to isolate legacy systems that cannot be migrated")
    if has_modern or not has_legacy:
        lines.append("- Implement Credential Guard on Windows 10+ endpoints")
    lines.append("- Deploy LAPS (Local Administrator Password Solution) domain-wide")
    lines.append("- Implement network segmentation (workstation/server VLANs)")
    lines.append("- Deploy Sysmon with tuned configuration for enhanced endpoint telemetry")
    lines.append("- Conduct tabletop exercise based on identified attack patterns")
    lines.append("")
    return lines


def _section_9_closing(ctx) -> list[str]:
    lines = ["## 9. Closing", ""]
    lines.append(f"This investigation was conducted autonomously by graphir in {ctx['elapsed_s']:.0f} seconds. ")
    lines.append(f"{ctx['verifications']} findings were structurally verified. ")
    lines.append(f"{len(ctx['corrections'])} self-correction(s) were recorded. ")
    lines.append(f"Evidence provenance coverage: {ctx['prov_pct']}.")
    lines.append("")
    lines.append("All findings carry explicit confidence levels. Analysts should review ")
    lines.append("INFERENCE-level findings with additional evidence before acting on them. ")
    lines.append("The complete evidence chain, investigation log, Sigma rules, and ATT&CK ")
    lines.append("Navigator layer are available in the investigation-output directory.")
    lines.append("")
    lines.append("---")
    lines.append(f"*graphir — Graph-based Autonomous Incident Response*")
    lines.append(f"*Investigation ID: {ctx['investigation_id']}*")
    lines.append(f"*{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")
    return lines


def _section_10_appendix(ctx, run_cypher) -> list[str]:
    lines = ["", "## Appendix A: Indicators of Compromise (IOCs)", ""]

    # Hashes from executables
    try:
        hashes = run_cypher("""
            MATCH (x:Executable)
            WHERE x.sha1 IS NOT NULL AND x.sha1 <> ''
            OPTIONAL MATCH (x)-[:ENRICHED_BY]->(ti:ThreatIntel)
            OPTIONAL MATCH (h:Host)-[:HAS_EXECUTABLE]->(x)
            RETURN x.name AS name, x.sha1 AS sha1,
                   ti.family AS family, ti.detection_rate AS detections,
                   collect(DISTINCT h.hostname)[0..3] AS hosts
            ORDER BY x.name
            LIMIT 50
        """)
        if hashes:
            lines.append("### File Hashes")
            lines.append("")
            lines.append("| Executable | SHA1 | VT Family | Detections | Hosts |")
            lines.append("|------------|------|-----------|------------|-------|")
            for h in hashes:
                name = str(h.get("name", ""))
                # Shorten long paths
                if "\\" in name:
                    name = name.split("\\")[-1]
                sha1 = h.get("sha1", "")
                family = h.get("family", "") or ""
                det = h.get("detections", "") or ""
                hosts = ", ".join([x for x in h.get("hosts", []) if x][:2])
                lines.append(f"| {name} | `{sha1}` | {family} | {det} | {hosts} |")
            lines.append("")
    except Exception:
        pass

    # Hosts involved
    if ctx["hosts"]:
        lines.append("### Hosts")
        lines.append("")
        for h in ctx["hosts"]:
            lines.append(f"- {h}")
        lines.append("")

    # Accounts of interest
    suspicious_users = [u for u in ctx["users"]
                       if u.get("user", "") not in ("SYSTEM", "ANONYMOUS LOGON", "unknown")
                       and not u.get("user", "").endswith("$")]
    if suspicious_users:
        lines.append("### Accounts of Interest")
        lines.append("")
        for u in suspicious_users[:10]:
            lines.append(f"- **{u['user']}** ({u.get('domain', '')}) — {u.get('logons', 0)} logons")
        lines.append("")

    # ATT&CK techniques observed
    techniques = set()
    for f in ctx["active_findings"]:
        tech = f.get("technique", "")
        tactic = f.get("tactic", "")
        if tech:
            techniques.add((tech, tactic))
    if techniques:
        lines.append("### MITRE ATT&CK Techniques Observed")
        lines.append("")
        lines.append("| Technique | Tactic |")
        lines.append("|-----------|--------|")
        for tech, tactic in sorted(techniques):
            lines.append(f"| {tech} | {tactic} |")
        lines.append("")

    # Reproducibility: key Cypher queries
    lines.append("### Appendix B: Investigation Queries (Reproducibility)")
    lines.append("")
    lines.append("The following Cypher queries can be used to reproduce key findings in the Neo4j graph:")
    lines.append("")
    lines.append("```cypher")
    lines.append("-- Lateral movement: network logons across hosts")
    lines.append("MATCH (u:User)-[r:LOGGED_ON]->(h:Host)")
    lines.append("WHERE r.logon_type IN [3, 9, 10]")
    lines.append("RETURN u.name, h.hostname, r.logon_type, count(*) AS sessions")
    lines.append("ORDER BY sessions DESC")
    lines.append("")
    lines.append("-- Temporal anomaly: files born recently in old directories")
    lines.append("MATCH (f:File)")
    lines.append("WHERE f.born_time > datetime('2012-04-01')")
    lines.append("  AND (f.name ENDS WITH '.exe' OR f.name ENDS WITH '.dll')")
    lines.append("RETURN f.name, f.path, f.born_time")
    lines.append("ORDER BY f.born_time")
    lines.append("")
    lines.append("-- Cross-host attack path")
    lines.append("MATCH path = shortestPath((src)-[:SPAWNED|ACCESSED|LOGGED_ON*1..10]-(dst))")
    lines.append("WHERE src.name CONTAINS 'suspicious' AND dst.hostname = 'CONTROLLER'")
    lines.append("RETURN path")
    lines.append("")
    lines.append("-- Threat intelligence enrichment")
    lines.append("MATCH (x:Executable)-[:ENRICHED_BY]->(ti:ThreatIntel)")
    lines.append("WHERE ti.detections > 0")
    lines.append("RETURN x.name, ti.family, ti.detection_rate")
    lines.append("```")
    lines.append("")

    # Output artifacts
    lines.append("### Appendix C: Output Artifacts")
    lines.append("")
    lines.append("| File | Description |")
    lines.append("|------|-------------|")
    lines.append("| `investigative-report.md` | This report (Markdown source) |")
    lines.append("| `investigative-report.pdf` | This report (PDF) |")
    lines.append("| `investigative-report.docx` | This report (DOCX) |")
    lines.append("| `audit-report.md/json` | Technical audit trail |")
    lines.append("| `evidence-chain.json` | Full provenance chain |")
    lines.append("| `navigator-layer.json` | ATT&CK Navigator layer |")
    lines.append("| `sigma-rules/*.yml` | Sigma detection rules |")
    lines.append("| `logs/*.jsonl` | Investigation session log |")
    lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Cell formatting
# ---------------------------------------------------------------------------

def _format_cell(key: str, value) -> str:
    """Format a table cell value for readability in markdown.

    Wraps long values using <br> for markdown table compatibility.
    Extracts filenames from paths, cleans timestamps, formats lists.
    """
    if value is None:
        return ""
    s = str(value)

    # File/path fields: extract readable portion
    if key in ("file", "path", "name", "executable", "dir_path") and "\\" in s:
        # Remove NTFS: prefix
        s = s.replace("NTFS:", "").replace("\\\\??\\\\", "")
        # If still long, keep last 3 components
        parts = s.split("\\")
        parts = [p for p in parts if p]
        if len(parts) > 4:
            s = "...\\\\" + "\\\\".join(parts[-3:])

    # Timestamp fields: strip nanoseconds and timezone
    if any(ts_key in key for ts_key in ["born", "modified", "accessed", "seen", "earliest", "latest"]):
        if "T" in s and "." in s:
            s = s.split(".")[0]
        s = s.replace("+00:00", "")

    # List fields: format nicely
    if isinstance(value, list):
        if not value:
            return ""
        if isinstance(value[0], dict):
            # List of dicts (e.g., recently_dropped) — extract names
            names = []
            for item in value[:3]:
                if isinstance(item, dict):
                    n = item.get("name", item.get("born", str(item)))
                    if isinstance(n, str) and "\\" in n:
                        n = n.split("\\")[-1]
                    names.append(str(n)[:40])
            s = ", ".join(names)
            if len(value) > 3:
                s += f" +{len(value)-3} more"
        elif isinstance(value[0], str):
            # List of strings — extract filenames
            items = []
            for v in value[:3]:
                v_str = str(v)
                if "\\" in v_str:
                    v_str = v_str.split("\\")[-1]
                items.append(v_str[:40])
            s = ", ".join(items)
            if len(value) > 3:
                s += f" +{len(value)-3} more"
        else:
            s = str(value)

    # Duration/window fields
    if key in ("delta", "window") and isinstance(value, list):
        if len(value) >= 3:
            s = f"{value[0]}m {value[1]}d {value[2]}s"

    # Wrap long values with <br> for markdown tables
    if len(s) > 80:
        # Break at sensible points
        wrapped = []
        while len(s) > 80:
            break_at = s.rfind("\\", 0, 80)
            if break_at < 20:
                break_at = s.rfind(",", 0, 80)
            if break_at < 20:
                break_at = 80
            wrapped.append(s[:break_at])
            s = s[break_at:]
        wrapped.append(s)
        s = "<br>".join(wrapped)

    return s
