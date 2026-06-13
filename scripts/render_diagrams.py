"""Render graphir's graph diagrams to SVG/PNG via Graphviz.

Produces two figures in docs/img/:
  schema.{svg,png}        — the meta-model: 13 vertex types / 15 edge types,
                            colour-grouped by the four fractal layers
                            (L0 investigation / L1 behaviour / L2 substance /
                            L3 evidence).
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

# Fractal-layer palette (fill, font).
LAYER = {
    "L0": ("#7c3aed", "white"),   # investigation
    "L1": ("#2563eb", "white"),   # behaviour
    "L2": ("#0891b2", "white"),   # substance
    "L3": ("#64748b", "white"),   # evidence
}


def _render(name: str, dot_src: str) -> None:
    dot_path = OUT / f"{name}.dot"
    dot_path.write_text(dot_src)
    for fmt in ("svg", "png"):
        subprocess.run(["dot", f"-T{fmt}", str(dot_path),
                        "-o", str(OUT / f"{name}.{fmt}")], check=True)
    print(f"  wrote {name}.svg / {name}.png")


def schema_dot() -> str:
    """Hand-authored meta-model — stable, doesn't depend on the DB."""
    def node(nid, label, layer):
        fill, font = LAYER[layer]
        return (f'  {nid} [label="{label}", style="filled,rounded", '
                f'shape=box, fillcolor="{fill}", fontcolor="{font}", '
                f'color="{fill}"];')

    nodes = [
        ("Incident", "Incident", "L0"),
        ("Finding", "Finding", "L0"),
        ("Correction", "Correction", "L0"),
        ("Claim", "Claim", "L0"),
        ("User", "User", "L1"),
        ("Process", "Process", "L1"),
        ("Host", "Host", "L2"),
        ("Executable", "Executable", "L2"),
        ("File", "File", "L2"),
        ("Connection", "Connection", "L2"),
        ("ThreatIntel", "ThreatIntel", "L2"),
        ("Event", "Event", "L3"),
        ("Artifact", "Artifact\\n(source file + parser)", "L3"),
    ]
    edges = [
        ("Finding", "Incident", "PART_OF"),
        ("Finding", "User", "SUPPORTED_BY"),
        ("Finding", "Executable", "SUPPORTED_BY"),
        ("Correction", "Claim", "CORRECTS"),
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
    clusters = {
        "L0": ("L0 — INVESTIGATION", ["Incident", "Finding", "Correction", "Claim"]),
        "L1": ("L1 — BEHAVIOUR", ["User", "Process"]),
        "L2": ("L2 — SUBSTANCE", ["Host", "Executable", "File", "Connection", "ThreatIntel"]),
        "L3": ("L3 — EVIDENCE", ["Event", "Artifact"]),
    }
    lines = [
        'digraph graphir_schema {',
        '  rankdir=TB; bgcolor="white"; pad=0.4; nodesep=0.4; ranksep=0.7;',
        '  node [fontname="Helvetica", fontsize=11];',
        '  edge [fontname="Helvetica", fontsize=9, color="#94a3b8", fontcolor="#475569"];',
        '  labelloc="t"; fontsize=16; fontname="Helvetica-Bold";',
        '  label="graphir graph schema — 13 vertex types, 15 edge types\\l'
        'fractal: Incident -> Finding -> entity -> Artifact (case narrative to raw line)\\l";',
    ]
    for layer, (title, members) in clusters.items():
        fill, _ = LAYER[layer]
        lines.append(f'  subgraph cluster_{layer} {{')
        lines.append(f'    label="{title}"; style="rounded,dashed"; '
                     f'color="{fill}"; fontcolor="{fill}"; fontsize=12;')
        for nid, label, lyr in nodes:
            if nid in members:
                lines.append("  " + node(nid, label, lyr))
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
        f'  INC [label="Incident\\n{inc}", fillcolor="#7c3aed", fontcolor="white", color="#7c3aed"];',
    ]
    seen = set()

    def ent_node(lbl, name):
        nid = f"{lbl}_{abs(hash(name)) % 100000}"
        if nid not in seen:
            seen.add(nid)
            fill = {"User": "#2563eb", "Host": "#0891b2",
                    "Executable": "#0891b2", "File": "#0891b2"}.get(lbl, "#64748b")
            lines.append(f'  {nid} [label="{lbl}\\n{short(name)}", '
                         f'fillcolor="{fill}", fontcolor="white", color="{fill}"];')
        return nid

    for f in findings:
        fid = f"F_{f['id'][:8]}"
        lines.append(f'  {fid} [label="Finding\\n{f["phase"]}\\n{f["conf"]} ({f["tech"]})", '
                     f'fillcolor="#7c3aed", fontcolor="white", color="#7c3aed"];')
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
                         f'fillcolor="#64748b", fontcolor="white", color="#64748b"];')
        lines.append(f'  {en} -> {aid} [label="DERIVED_FROM\\nline {d["line"]}", style=dashed];')
    for c in claim:
        cid = f"CL_{c['id'][:8]}"
        if cid not in seen:
            seen.add(cid)
            lines.append(f'  {cid} [label="Claim\\n{c["conf"]}", '
                         f'fillcolor="#7c3aed", fontcolor="white", color="#7c3aed"];')
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
