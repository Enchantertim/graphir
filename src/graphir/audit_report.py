"""Audit report generator — complete investigation package in one call.

Generates a structured investigation report that traces every finding
through the full verification chain: finding → atomic claims → predicates
→ graph entities → origin artifacts → source line numbers.

Designed to be handed to:
  - A hackathon judge (prove the system is rigorous)
  - A SOC manager (actionable summary + deployed detections)
  - Legal/compliance (admissible chain of custody)

The report includes:
  1. Executive summary (what happened, top actions)
  2. Findings with confidence levels and structural evidence
  3. Verification audit trail (which predicates passed/failed, why)
  4. Corrections (what was flagged as FP/hallucination/unsupported)
  5. Provenance integrity (coverage stats, chain completeness)
  6. Output artifacts generated (Sigma rules, Navigator layer, evidence chain)
  7. Investigation metadata (tools called, time elapsed, session ID)
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_audit_report(
    run_cypher,
    investigation_log,
    findings: list[dict],
    verification_results: list[dict] | None = None,
    output_dir: str = "investigation-output",
) -> dict:
    """Generate a complete audit report from the investigation state.

    Args:
        run_cypher: Cypher execution function
        investigation_log: InvestigationLog instance
        findings: find_evil results
        verification_results: Optional list of verify_finding outputs
        output_dir: Where to write the report

    Returns:
        Report dict + path to written file
    """
    report = {
        "report_type": "graphir_audit_report",
        "generated": datetime.now(timezone.utc).isoformat(),
        "investigation_id": investigation_log.investigation_id,
    }

    # 1. Executive summary
    report["executive_summary"] = _build_executive_summary(
        run_cypher, findings, investigation_log
    )

    # 2. Findings detail
    report["findings"] = _build_findings_detail(findings)

    # 3. Verification audit trail
    report["verification_trail"] = _build_verification_trail(investigation_log)

    # 4. Corrections
    report["corrections"] = _get_corrections(run_cypher)

    # 5. Provenance integrity
    report["provenance"] = _get_provenance_stats(run_cypher)

    # 6. Graph overview
    report["graph_overview"] = _get_graph_overview(run_cypher)

    # 7. Output artifacts
    report["artifacts"] = _list_artifacts(output_dir)

    # 8. Investigation metadata
    report["metadata"] = _build_metadata(
        investigation_log,
        graph_corrections_count=report["corrections"]["total"],
    )

    # Write report
    report_path = Path(output_dir) / "audit-report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Also write a human-readable markdown version
    md_path = Path(output_dir) / "audit-report.md"
    with open(md_path, "w") as f:
        f.write(_render_markdown(report))

    return {
        "status": "ok",
        "json_path": str(report_path),
        "markdown_path": str(md_path),
        "findings_count": len(report["findings"]),
        "corrections_count": report["corrections"]["total"],
        "provenance_coverage": report["provenance"]["coverage"],
    }


def _build_executive_summary(run_cypher, findings, log) -> dict:
    """One-paragraph summary: what happened, what was found, what to do."""
    # Get host info
    hosts = run_cypher("MATCH (h:Host) WHERE h.hostname IS NOT NULL RETURN h.hostname LIMIT 5")
    host_names = [h["h.hostname"] for h in hosts]

    # Get user info
    users = run_cypher("""
        MATCH (u:User)-[r:LOGGED_ON]->(h:Host)
        WHERE u.name <> 'SYSTEM' AND NOT u.name ENDS WITH '$'
        RETURN u.name AS user, count(r) AS logons
        ORDER BY logons DESC LIMIT 5
    """)

    # Count findings by category
    hunt_names = [f.get("hunt", "") for f in findings if isinstance(f, dict)]
    total_hits = sum(f.get("hit_count", 0) for f in findings if isinstance(f, dict))

    # Get log summary
    log_summary = log.get_summary()
    confirmed = log_summary.get("findings", {}).get("by_confidence", {}).get("CONFIRMED", 0)
    insufficient = log_summary.get("findings", {}).get("by_confidence", {}).get("INSUFFICIENT_EVIDENCE", 0)

    return {
        "hosts_investigated": host_names,
        "primary_users": [u["user"] for u in users],
        "hunt_categories_triggered": len(hunt_names),
        "total_indicators": total_hits,
        "findings_confirmed": confirmed,
        "findings_insufficient": insufficient,
        "investigation_duration_s": log_summary.get("elapsed_s", 0),
    }


def _build_findings_detail(findings: list[dict]) -> list[dict]:
    """Structured finding details with results and context."""
    details = []
    for f in findings:
        if isinstance(f, dict) and "hunt" in f:
            # Summarize results for readability
            results = f.get("results", [])
            result_summary = []
            for r in results[:10]:
                # Extract the most informative fields
                clean = {k: v for k, v in r.items()
                         if v is not None and v != "" and v != []}
                result_summary.append(clean)

            details.append({
                "hunt": f.get("hunt"),
                "technique": f.get("technique"),
                "tactic": f.get("tactic"),
                "description": f.get("description"),
                "hit_count": f.get("hit_count", 0),
                "results": result_summary,
            })
    return details


def _build_verification_trail(log) -> list[dict]:
    """Extract verification entries from the investigation log."""
    trail = []
    for entry in log.entries:
        if entry["entry_type"] == "verification":
            trail.append({
                "timestamp": entry["timestamp"],
                "claim": entry["detail"],
                "confidence": entry["data"].get("confidence", ""),
                "predicates_passed": entry["data"].get("predicates_passed", []),
                "predicates_failed": entry["data"].get("predicates_failed", []),
                "divergences": entry["data"].get("divergences", []),
            })
        elif entry["entry_type"] == "finding":
            trail.append({
                "timestamp": entry["timestamp"],
                "type": "finding",
                "detail": entry["detail"],
                "confidence": entry["data"].get("confidence", ""),
                "claim_summary": entry["data"].get("claim_summary", {}),
            })
    return trail


def _get_corrections(run_cypher) -> dict:
    """Get all corrections from the graph."""
    try:
        corrections = run_cypher("""
            MATCH (c:Correction)
            RETURN c.correction_id AS id, c.type AS type,
                   c.reason AS reason, c.original_claim AS claim,
                   c.corrected_by AS by, c.timestamp AS ts
            ORDER BY c.timestamp
        """)
        by_type = run_cypher("""
            MATCH (c:Correction)
            WITH c.type AS type, count(*) AS cnt
            RETURN type, cnt ORDER BY cnt DESC
        """)
        return {
            "total": len(corrections),
            "by_type": by_type,
            "details": corrections,
        }
    except Exception:
        return {"total": 0, "by_type": [], "details": []}


def _get_provenance_stats(run_cypher) -> dict:
    """Get provenance coverage stats."""
    try:
        results = run_cypher("""
            MATCH (n) WHERE NOT n:Host
            WITH labels(n)[0] AS label,
                 count(*) AS total,
                 sum(CASE WHEN n._origin_tool IS NOT NULL THEN 1 ELSE 0 END) AS with_origin
            RETURN label, total, with_origin
            ORDER BY total DESC
        """)
        total = sum(r["total"] for r in results)
        with_origin = sum(r["with_origin"] for r in results)
        return {
            "total_entities": total,
            "with_origin": with_origin,
            "coverage": f"{with_origin / total * 100:.1f}%" if total else "N/A",
            "by_type": results,
        }
    except Exception:
        return {"total_entities": 0, "with_origin": 0, "coverage": "N/A", "by_type": []}


def _get_graph_overview(run_cypher) -> dict:
    """Get graph node/edge counts and time range."""
    try:
        nodes = run_cypher("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS cnt ORDER BY cnt DESC")
        edges = run_cypher("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS cnt ORDER BY cnt DESC")
        time_range = run_cypher("""
            MATCH ()-[r]->()
            WHERE r.timestamp IS NOT NULL
            RETURN min(r.timestamp) AS earliest, max(r.timestamp) AS latest
        """)
        return {
            "nodes": nodes,
            "edges": edges,
            "time_range": time_range[0] if time_range else {},
        }
    except Exception:
        return {"nodes": [], "edges": [], "time_range": {}}


def _list_artifacts(output_dir: str) -> list[dict]:
    """List all generated output artifacts."""
    artifacts = []
    out_path = Path(output_dir)
    if out_path.exists():
        for f in sorted(out_path.rglob("*")):
            if f.is_file() and f.name != ".DS_Store":
                artifacts.append({
                    "file": str(f.relative_to(out_path)),
                    "size_bytes": f.stat().st_size,
                    "type": f.suffix.lstrip("."),
                })
    return artifacts


def _build_metadata(log, graph_corrections_count: int = 0) -> dict:
    """Investigation session metadata."""
    summary = log.get_summary()
    return {
        "investigation_id": log.investigation_id,
        "log_path": str(log.log_path),
        "total_log_entries": summary.get("total_entries", 0),
        "elapsed_s": summary.get("elapsed_s", 0),
        "tool_calls": summary.get("by_type", {}).get("tool_call", 0),
        "verifications": summary.get("verifications", 0),
        "findings_logged": summary.get("findings", {}).get("total", 0),
        "corrections_this_session": summary.get("corrections", 0),
        "corrections_total_in_graph": graph_corrections_count,
        "self_corrections": summary.get("self_corrections", 0),
    }


def _render_markdown(report: dict) -> str:
    """Render the audit report as human-readable markdown."""
    lines = []
    lines.append("# graphir Audit Report")
    lines.append("")
    lines.append(f"**Generated:** {report['generated']}")
    lines.append(f"**Investigation ID:** {report['investigation_id']}")
    lines.append("")

    # Executive summary
    es = report["executive_summary"]
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Hosts:** {', '.join(es.get('hosts_investigated', []))}")
    lines.append(f"- **Primary users:** {', '.join(es.get('primary_users', []))}")
    lines.append(f"- **Hunt categories triggered:** {es.get('hunt_categories_triggered', 0)}")
    lines.append(f"- **Total indicators:** {es.get('total_indicators', 0)}")
    lines.append(f"- **Findings confirmed:** {es.get('findings_confirmed', 0)}")
    lines.append(f"- **Findings insufficient evidence:** {es.get('findings_insufficient', 0)}")
    lines.append(f"- **Investigation duration:** {es.get('investigation_duration_s', 0):.0f}s")
    lines.append("")

    # Findings
    lines.append("## Findings")
    lines.append("")
    for f in report["findings"]:
        lines.append(f"### [{f.get('technique', '?')}] {f.get('description', '')}")
        lines.append(f"- **Tactic:** {f.get('tactic', '')}")
        lines.append(f"- **Hits:** {f.get('hit_count', 0)}")
        lines.append("")
        # Show result data
        for r in f.get("results", [])[:5]:
            parts = [f"**{k}:** {v}" for k, v in r.items()
                     if v is not None and v != "" and v != []]
            if parts:
                lines.append(f"  - {' | '.join(parts[:4])}")
        if f.get("hit_count", 0) > 5:
            lines.append(f"  - *... and {f['hit_count'] - 5} more*")
        lines.append("")

    # Verification trail
    lines.append("## Verification Audit Trail")
    lines.append("")
    for v in report["verification_trail"]:
        ts = v.get("timestamp", "")[:19]
        vtype = v.get("type", "verification")
        conf = v.get("confidence", "")
        detail = v.get("claim", v.get("detail", ""))

        if vtype == "verification":
            passed = v.get("predicates_passed", [])
            failed = v.get("predicates_failed", [])
            lines.append(f"### [{conf}] {detail}")
            lines.append(f"- **Time:** {ts}")
            if passed:
                lines.append(f"- **Passed:** {', '.join(passed)}")
            if failed:
                lines.append(f"- **Failed:** {', '.join(failed)}")
            for d in v.get("divergences", []):
                lines.append(f"- **Divergence:** {d.get('predicate', '?')} — "
                             f"{d.get('reason', '?')}: {d.get('detail', '')}")
            lines.append("")
        elif vtype == "finding":
            lines.append(f"**Finding logged:** {detail} → **{conf}**")
            claim_summary = v.get("claim_summary", {})
            if claim_summary:
                lines.append(f"  - Claims: {claim_summary}")
            lines.append("")

    # Corrections
    corr = report["corrections"]
    lines.append("## Corrections")
    lines.append("")
    lines.append(f"**Total corrections:** {corr.get('total', 0)}")
    lines.append("")
    for c in corr.get("details", []):
        lines.append(f"### [{c.get('type', '?')}] {c.get('claim', '')}")
        lines.append(f"- **Corrected by:** {c.get('by', '?')}")
        lines.append(f"- **Reason:** {c.get('reason', '')}")
        lines.append(f"- **Time:** {c.get('ts', '')}")
        lines.append("")

    # Provenance
    prov = report["provenance"]
    lines.append("## Provenance Integrity")
    lines.append("")
    lines.append(f"**Coverage:** {prov.get('coverage', 'N/A')} ({prov.get('with_origin', 0)}/{prov.get('total_entities', 0)} entities with origin)")
    lines.append("")
    lines.append("| Entity Type | Total | With Origin | Coverage |")
    lines.append("|-------------|-------|-------------|----------|")
    for t in prov.get("by_type", []):
        total = t.get("total", 0)
        origin = t.get("with_origin", 0)
        pct = f"{origin/total*100:.0f}%" if total else "N/A"
        lines.append(f"| {t.get('label', '?')} | {total} | {origin} | {pct} |")
    lines.append("")

    # Graph overview
    go = report["graph_overview"]
    lines.append("## Graph Overview")
    lines.append("")
    for n in go.get("nodes", []):
        lines.append(f"- **{n.get('label', '?')}:** {n.get('cnt', 0):,}")
    lines.append("")

    # Artifacts
    lines.append("## Output Artifacts")
    lines.append("")
    for a in report["artifacts"]:
        size_kb = a.get("size_bytes", 0) / 1024
        lines.append(f"- `{a['file']}` ({size_kb:.1f} KB)")
    lines.append("")

    # Metadata
    meta = report["metadata"]
    lines.append("## Investigation Metadata")
    lines.append("")
    lines.append(f"- **Session ID:** {meta.get('investigation_id', '')}")
    lines.append(f"- **Duration:** {meta.get('elapsed_s', 0):.0f}s")
    lines.append(f"- **Tool calls:** {meta.get('tool_calls', 0)}")
    lines.append(f"- **Verifications:** {meta.get('verifications', 0)}")
    lines.append(f"- **Findings logged:** {meta.get('findings_logged', 0)}")
    lines.append(f"- **Corrections (this session):** {meta.get('corrections_this_session', 0)}")
    lines.append(f"- **Corrections (total in graph):** {meta.get('corrections_total_in_graph', 0)}")
    lines.append(f"- **Log file:** `{meta.get('log_path', '')}`")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by graphir — Graph-based Autonomous Incident Response*")

    return "\n".join(lines)
