"""Render graphir's graph diagrams to SVG/PNG via Graphviz.

Produces two figures in docs/img/:
  schema.{svg,png}        — the meta-model: 13 entity types / 15 relationship
                            types, grouped into subsystem clusters with the
                            high-degree hub types (Host, User, Executable, File,
                            Finding, Event) highlighted in blue.
  example-graph.{svg,png} — a real slice of the loaded investigation graph
                            (Incident -> Finding -> entity -> Artifact, plus a
                            verified Claim and a lateral-movement hop), queried
                            live from Neo4j.

Usage:
    .venv/bin/python scripts/render_diagrams.py
Requires the `dot` binary (graphviz) on PATH and, for the example graph, a
populated Neo4j (docker compose up + an ingested + reconstructed case).
"""

import os
import shutil
import subprocess
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "docs" / "img"


def _render(name: str, dot_src: str) -> None:
    dot_path = OUT / f"{name}.dot"
    dot_path.write_text(dot_src)
    for fmt in ("svg", "png"):
        subprocess.run(["dot", f"-T{fmt}", str(dot_path),
                        "-o", str(OUT / f"{name}.{fmt}")], check=True)
    print(f"  wrote {name}.svg / {name}.png")


def schema_dot() -> str:
    """Hand-authored meta-model in the domain-clustered ER-map style:
    subsystem clusters, high-degree hub types highlighted, labelled edges.
    """
    HUB = "#1f6fe5"          # blue hub fill
    LEAF = "#ededed"         # light grey leaf fill
    # Hub = high-degree backbone types; everything else renders as a grey leaf.
    hubs = {"Host", "User", "Executable", "File", "Finding", "Event"}

    # Domain clusters (title, members) — graphir's actual subsystems.
    clusters = [
        ("Investigation / Reporting", ["Incident", "Finding"]),
        ("Verification", ["Claim", "Correction"]),
        ("Identity", ["User"]),
        ("Execution & Binaries", ["Process", "Executable"]),
        ("Filesystem", ["File"]),
        ("Hosts & Network", ["Host", "Connection"]),
        ("Threat Intelligence", ["ThreatIntel"]),
        ("Evidence & Provenance", ["Event", "Artifact"]),
    ]
    labels = {"Artifact": "Artifact\\n(source file + parser)"}
    edges = [
        ("Finding", "Incident", "PART_OF"),
        ("Finding", "User", "SUPPORTED_BY"),
        ("Finding", "Executable", "SUPPORTED_BY"),
        ("Finding", "Host", "SUPPORTED_BY"),
        ("Correction", "Claim", "CORRECTS"),
        ("Correction", "Finding", "CORRECTS"),
        ("Claim", "User", "ABOUT"),
        ("User", "Host", "LOGGED_ON"),
        ("Process", "Process", "SPAWNED"),
        ("Process", "Host", "EXECUTED_ON"),
        ("Process", "Process", "ACCESSED"),
        ("Host", "Host", "CONNECTED_TO"),
        ("Host", "Executable", "HAS_EXECUTABLE"),
        ("Host", "File", "MODIFIED"),
        ("Executable", "File", "SAME_BINARY"),
        ("Executable", "ThreatIntel", "ENRICHED_BY"),
        ("Event", "Host", "ON_HOST"),
        ("File", "Artifact", "DERIVED_FROM"),
        ("Executable", "Artifact", "DERIVED_FROM"),
    ]
    lines = [
        'digraph graphir_schema {',
        '  rankdir=TB; bgcolor="white"; pad=0.5; nodesep=0.35; ranksep=0.9;',
        '  compound=true; splines=true; concentrate=false;',
        '  node [shape=box, style=filled, fontname="Helvetica", fontsize=11,'
        f'        fillcolor="{LEAF}", color="#c4c4c4", fontcolor="#1a1a1a", penwidth=1];',
        '  edge [fontname="Helvetica", fontsize=8, color="#9aa0a6",'
        '        fontcolor="#5f6368", arrowsize=0.7, penwidth=0.9];',
        '  labelloc="t"; fontsize=17; fontname="Helvetica-Bold"; fontcolor="#1a1a1a";',
        '  label="graphir graph schema — 13 entity types, 15 relationship types\\l'
        '(blue = high-degree hub types; clusters = subsystems)\\l";',
    ]
    for i, (title, members) in enumerate(clusters):
        lines.append(f'  subgraph cluster_{i} {{')
        lines.append(f'    label="{title}"; labelloc="t"; fontsize=10;'
                     '    style="filled,rounded"; fillcolor="#fbfbfb";'
                     '    color="#d0d0d0"; fontcolor="#8a8a8a";')
        for nid in members:
            label = labels.get(nid, nid)
            if nid in hubs:
                lines.append(f'    {nid} [label="{label}", fillcolor="{HUB}", '
                             f'fontcolor="white", color="{HUB}"];')
            else:
                lines.append(f'    {nid} [label="{label}"];')
        lines.append('  }')
    for s, d, lbl in edges:
        style = ' style=dashed' if lbl in ("DERIVED_FROM", "ENRICHED_BY") else ''
        lines.append(f'  {s} -> {d} [label="{lbl}"{style}];')
    lines.append('}')
    return "\n".join(lines)


def example_dot(run_cypher) -> str:
    """Live slice of the investigation graph — real nodes from the loaded case."""
    inc = "SANS508-SRL-APT"
    # Balanced selection so both phases appear (lateral_movement sorts after
    # defense_evasion, so a plain LIMIT would drop it): all lateral hops + a
    # couple of defense-evasion findings.
    findings = run_cypher("""
        MATCH (fi:Finding {investigation_id: $inc})
        WITH fi ORDER BY fi.phase DESC, fi.finding_id
        WITH collect(fi) AS all
        WITH [f IN all WHERE f.phase = 'lateral_movement'][0..3] +
             [f IN all WHERE f.phase <> 'lateral_movement'][0..2] AS chosen
        UNWIND chosen AS fi
        RETURN fi.finding_id AS id, fi.phase AS phase, fi.confidence AS conf,
               fi.technique AS tech
    """, {"inc": inc})
    fids = [f["id"] for f in findings]
    support = run_cypher("""
        MATCH (fi:Finding)-[:SUPPORTED_BY]->(e)
        WHERE fi.finding_id IN $fids
        RETURN fi.finding_id AS fid, labels(e)[0] AS lbl,
               coalesce(e.name, e.hostname) AS name LIMIT 14
    """, {"fids": fids})
    derived = run_cypher("""
        MATCH (fi:Finding)-[:SUPPORTED_BY]->(x:Executable)-[d:DERIVED_FROM]->(a:Artifact)
        WHERE fi.finding_id IN $fids
        RETURN DISTINCT x.name AS exe, a.path AS artifact, d.source_line AS line
        LIMIT 3
    """, {"fids": fids})
    claim = run_cypher("""
        MATCH (cl:Claim)-[:ABOUT]->(e)
        RETURN cl.claim_id AS id, cl.statement AS stmt, cl.confidence AS conf,
               labels(e)[0] AS lbl, coalesce(e.name, e.hostname) AS name LIMIT 4
    """)

    def esc(s):
        return str(s).replace('"', "'").replace("\\", "/")[:46]

    def short(s):
        s = esc(s)
        return s.rsplit("/", 1)[-1] if "/" in s else s

    lines = [
        'digraph graphir_example {',
        '  rankdir=LR; bgcolor="white"; pad=0.4; nodesep=0.35; ranksep=0.9;',
        '  node [fontname="Helvetica", fontsize=10, style="filled,rounded", shape=box];',
        '  edge [fontname="Helvetica", fontsize=8, color="#94a3b8", fontcolor="#475569"];',
        '  labelloc="t"; fontsize=15; fontname="Helvetica-Bold";',
        '  label="graphir — live investigation slice (SANS 508 / SHIELDBASE)\\l'
        'Incident -> Finding -> entity -> Artifact, with a verified Claim\\l";',
        f'  INC [label="Incident\\n{inc}", fillcolor="#ededed", fontcolor="#1a1a1a", color="#c4c4c4"];',
    ]
    seen = set()

    def ent_node(lbl, name):
        nid = f"{lbl}_{abs(hash(name)) % 100000}"
        if nid not in seen:
            seen.add(nid)
            if lbl in ("User", "Host", "Executable", "File"):  # hub types
                lines.append(f'  {nid} [label="{lbl}\\n{short(name)}", '
                             f'fillcolor="#1f6fe5", fontcolor="white", color="#1f6fe5"];')
            else:
                lines.append(f'  {nid} [label="{lbl}\\n{short(name)}", '
                             f'fillcolor="#ededed", fontcolor="#1a1a1a", color="#c4c4c4"];')
        return nid

    for f in findings:
        fid = f"F_{f['id'][:8]}"
        lines.append(f'  {fid} [label="Finding\\n{f["phase"]}\\n{f["conf"]} ({f["tech"]})", '
                     f'fillcolor="#1f6fe5", fontcolor="white", color="#1f6fe5"];')
        lines.append(f'  {fid} -> INC [label="PART_OF"];')
    for s in support:
        fid = f"F_{s['fid'][:8]}"
        en = ent_node(s["lbl"], s["name"])
        lines.append(f'  {fid} -> {en} [label="SUPPORTED_BY"];')
    for d in derived:
        en = ent_node("Executable", d["exe"])
        aid = f"A_{abs(hash(d['artifact'])) % 100000}"
        if aid not in seen:
            seen.add(aid)
            lines.append(f'  {aid} [label="Artifact\\n{short(d["artifact"])}", '
                         f'fillcolor="#ededed", fontcolor="#1a1a1a", color="#c4c4c4"];')
        lines.append(f'  {en} -> {aid} [label="DERIVED_FROM\\nline {d["line"]}", style=dashed];')
    for c in claim:
        cid = f"CL_{c['id'][:8]}"
        if cid not in seen:
            seen.add(cid)
            lines.append(f'  {cid} [label="Claim\\n{c["conf"]}", '
                         f'fillcolor="#ededed", fontcolor="#1a1a1a", color="#c4c4c4"];')
        en = ent_node(c["lbl"], c["name"])
        lines.append(f'  {cid} -> {en} [label="ABOUT"];')
    lines.append('}')
    return "\n".join(lines)


def main():
    if not shutil.which("dot"):
        raise SystemExit("graphviz 'dot' not found on PATH")
    OUT.mkdir(parents=True, exist_ok=True)
    print("Rendering schema diagram...")
    _render("schema", schema_dot())
    try:
        from graphir import server
        print("Rendering live example graph...")
        _render("example-graph", example_dot(server.run_cypher))
    except Exception as e:
        print(f"  skipped example-graph (need a populated Neo4j): {e}")


if __name__ == "__main__":
    main()
