"""Evidence chain generator — full provenance from finding to raw artifact.

For every confirmed/partial finding, traverses the graph to collect:
  finding → atomic claim → predicate → graph entities → _origin_* → raw artifact

Produces a JSON file that an auditor (or judge) can use to walk backwards
from any finding to the exact line in the source Plaso JSONL file.

Output structure:
{
  "investigation_id": "...",
  "generated": "2026-04-04T...",
  "findings": [
    {
      "finding_id": "...",
      "narrative": "...",
      "confidence": "CONFIRMED",
      "claims": [
        {
          "statement": "...",
          "confidence": "CONFIRMED",
          "predicates": [...],
          "evidence_entities": [
            {
              "type": "Process",
              "name": "cmd.exe",
              "origin": {
                "tool": "ingest_timeline",
                "artifact": "/evidence/Security.evtx",
                "parser": "winevtx",
                "data_type": "windows:evtx:record",
                "source_line": 4137938
              }
            }
          ]
        }
      ],
      "corrections": [...]
    }
  ],
  "provenance_summary": {
    "total_entities_referenced": 42,
    "with_origin": 40,
    "coverage": "95.2%"
  }
}
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def generate_evidence_chain(run_cypher, findings: list[dict],
                            investigation_id: str = "") -> dict:
    """Generate evidence chain JSON from investigation findings.

    Args:
        run_cypher: Cypher execution function
        findings: List of finding dicts from find_evil (summarized format)
        investigation_id: Optional investigation session ID

    Returns:
        Evidence chain dict with full provenance for every finding
    """
    chain = {
        "investigation_id": investigation_id,
        "generated": datetime.now(timezone.utc).isoformat(),
        "findings": [],
        "provenance_summary": {
            "total_entities_referenced": 0,
            "with_origin": 0,
            "without_origin": 0,
            "coverage": "0%",
        },
    }

    total_entities = 0
    with_origin = 0

    for finding in findings:
        if isinstance(finding, dict) and finding.get("status") == "clean":
            continue

        hunt = finding.get("hunt", "")
        technique = finding.get("technique", "")
        tactic = finding.get("tactic", "")
        description = finding.get("description", "")
        results = finding.get("results", [])

        if not results:
            continue

        # Collect entities referenced by this finding
        entities = _collect_entities_for_finding(run_cypher, hunt, results)
        total_entities += len(entities)
        with_origin += sum(1 for e in entities if e.get("origin", {}).get("tool"))

        # Check for corrections on this technique
        corrections = _get_corrections_for_technique(run_cypher, technique)

        finding_entry = {
            "hunt": hunt,
            "technique": technique,
            "tactic": tactic,
            "description": description,
            "hit_count": finding.get("hit_count", 0),
            "evidence_entities": entities,
            "entity_count": len(entities),
            "provenance_complete": all(
                e.get("origin", {}).get("tool") is not None for e in entities
            ) if entities else False,
            "corrections": corrections,
            "sample_results": results[:5],  # Include raw results for reference
        }

        chain["findings"].append(finding_entry)

    # Summary
    chain["provenance_summary"] = {
        "total_entities_referenced": total_entities,
        "with_origin": with_origin,
        "without_origin": total_entities - with_origin,
        "coverage": f"{with_origin / total_entities * 100:.1f}%" if total_entities else "N/A",
    }

    return chain


def _collect_entities_for_finding(run_cypher, hunt: str,
                                   results: list[dict]) -> list[dict]:
    """Collect graph entities with origin metadata for a finding's results."""
    entities = []
    seen = set()

    # Extract entity names from results based on hunt type
    # Separate by expected node type for targeted lookups
    process_names = set()
    host_names = set()
    user_names = set()
    service_names = set()

    for r in results:
        # Processes (full paths or short names)
        for key in ("parent", "ancestor", "child", "accessor", "tool",
                     "process", "proc_name"):
            val = r.get(key)
            if val and isinstance(val, str) and val not in ("", "unknown"):
                process_names.add(val)

        # Hosts
        for key in ("host", "source", "destination", "src_host"):
            val = r.get(key)
            if val and isinstance(val, str) and val:
                host_names.add(val)

        # Users
        for key in ("user",):
            val = r.get(key)
            if val and isinstance(val, str) and val not in ("", "unknown"):
                user_names.add(val)

        # Services
        for key in ("service",):
            val = r.get(key)
            if val and isinstance(val, str) and val:
                service_names.add(val)

    # Combine into names for backward compat
    names = process_names | host_names | user_names | service_names

    # Query graph for each entity's origin
    for name in names:
        if name in seen:
            continue
        seen.add(name)

        # Search specific labels with UNION — fast and type-aware
        try:
            results = run_cypher("""
                MATCH (p:Process) WHERE p.name CONTAINS $name
                RETURN 'Process' AS type, p.name AS name, p._origin_tool AS tool,
                       p._origin_artifact AS artifact, p._origin_parser AS parser,
                       p._origin_data_type AS data_type, p._origin_source_line AS source_line,
                       p._origin_derived_from_child_line AS derived_line
                LIMIT 2
                UNION ALL
                MATCH (x:Executable) WHERE x.name CONTAINS $name
                RETURN 'Executable' AS type, x.name AS name, x._origin_tool AS tool,
                       x._origin_artifact AS artifact, x._origin_parser AS parser,
                       x._origin_data_type AS data_type, x._origin_source_line AS source_line,
                       null AS derived_line
                LIMIT 2
                UNION ALL
                MATCH (h:Host) WHERE h.hostname = $name
                RETURN 'Host' AS type, h.hostname AS name, null AS tool,
                       null AS artifact, null AS parser, null AS data_type,
                       null AS source_line, null AS derived_line
                LIMIT 1
                UNION ALL
                MATCH (u:User) WHERE u.name = $name
                RETURN 'User' AS type, u.name AS name, u._origin_tool AS tool,
                       u._origin_artifact AS artifact, u._origin_parser AS parser,
                       u._origin_data_type AS data_type, u._origin_source_line AS source_line,
                       null AS derived_line
                LIMIT 1
            """, {"name": name})

            for r in results:
                origin = {}
                if r.get("tool"):
                    origin = {
                        "tool": r["tool"],
                        "artifact": r.get("artifact", ""),
                        "parser": r.get("parser", ""),
                        "data_type": r.get("data_type", ""),
                        "source_line": r.get("source_line"),
                    }
                    # If this is an inferred parent, note the derivation
                    if r["tool"] == "inferred_parent":
                        origin["derived"] = True
                        origin["derived_from_child_line"] = r.get("derived_line")
                elif r.get("derived_line"):
                    origin = {
                        "tool": "inferred_parent",
                        "derived": True,
                        "derived_from_child_line": r.get("derived_line"),
                    }

                entity_key = f"{r.get('type', '')}:{r.get('name', '')}"
                if entity_key not in seen:
                    seen.add(entity_key)
                    entities.append({
                        "type": r.get("type", "Unknown"),
                        "name": r.get("name", name),
                        "origin": origin,
                    })

        except Exception:
            entities.append({
                "type": "Unknown",
                "name": name,
                "origin": {},
                "error": "Failed to query origin",
            })

    return entities


def _get_corrections_for_technique(run_cypher, technique: str) -> list[dict]:
    """Get any corrections related to a technique."""
    if not technique:
        return []
    try:
        results = run_cypher("""
            MATCH (c:Correction)
            WHERE toLower(c.original_claim) CONTAINS toLower($technique)
               OR toLower(c.reason) CONTAINS toLower($technique)
            RETURN c.correction_id AS id,
                   c.type AS type,
                   c.reason AS reason,
                   c.corrected_by AS by,
                   c.original_claim AS claim
            LIMIT 10
        """, {"technique": technique})
        return results
    except Exception:
        return []


def write_evidence_chain(chain: dict,
                         output_path: str = "investigation-output/evidence-chain.json") -> dict:
    """Write evidence chain to JSON file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        json.dump(chain, f, indent=2, default=str)

    return {
        "status": "ok",
        "path": str(path),
        "findings": len(chain.get("findings", [])),
        "total_entities": chain["provenance_summary"]["total_entities_referenced"],
        "provenance_coverage": chain["provenance_summary"]["coverage"],
    }
