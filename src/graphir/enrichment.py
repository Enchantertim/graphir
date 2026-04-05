"""Threat intelligence enrichment — hash-based lookups and binary analysis.

Enriches Executable and File nodes with threat intelligence from external
sources (VirusTotal hash lookups) and local analysis (capa, yara).

Design principles:
  - Hash-only VT lookup, NEVER upload. Zero customer data exfiltration.
  - "Unknown hash" is itself a signal (novel malware vs known family).
  - Results written back to graph as ThreatIntel nodes linked via ENRICHED_BY.
  - Same provenance model as everything else — _origin_* on every node.

Graph pattern:
  (Executable {sha256: '...'})
    -[:ENRICHED_BY]-> (ThreatIntel {
        source: 'virustotal',
        family: 'Emotet',
        detections: 47,
        total_engines: 72,
        first_seen: '2011-...',
        _origin_tool: 'vt_hash_lookup'
    })
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# VT free tier: 4 req/min, 500/day
VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_RATE_LIMIT_SECONDS = 16  # ~4 req/min with margin


def vt_hash_lookup(file_hash: str) -> dict:
    """Look up a file hash on VirusTotal. Hash-only, never uploads.

    Args:
        file_hash: SHA256, SHA1, or MD5 hash string.

    Returns:
        Dict with detection info, or error/not_found status.
    """
    if not VT_API_KEY:
        return {"status": "no_api_key",
                "message": "Set VT_API_KEY environment variable for VirusTotal lookups."}

    import urllib.request
    import urllib.error

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": VT_API_KEY})

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        names = attrs.get("names", [])

        return {
            "status": "found",
            "hash": file_hash,
            "detections": stats.get("malicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "detection_rate": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "family": attrs.get("popular_threat_classification", {}).get(
                "suggested_threat_label", "unknown"
            ),
            "type_tag": attrs.get("type_tag", ""),
            "names": names[:5],
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "sha256": attrs.get("sha256", ""),
            "sha1": attrs.get("sha1", ""),
            "md5": attrs.get("md5", ""),
            "size": attrs.get("size"),
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {
                "status": "not_found",
                "hash": file_hash,
                "message": "Hash not found in VirusTotal. This could indicate novel malware.",
            }
        elif e.code == 429:
            return {"status": "rate_limited", "message": "VT rate limit hit. Wait and retry."}
        else:
            return {"status": "error", "message": f"VT API error: {e.code} {e.reason}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def enrich_executables_from_graph(run_cypher, max_lookups: int = 50,
                                  skip_known_good_paths: bool = True) -> dict:
    """Batch-enrich Executable nodes that have SHA1/SHA256 hashes.

    Queries VT for each hash and writes ThreatIntel nodes back to the graph.

    Args:
        run_cypher: Cypher execution function.
        max_lookups: Maximum VT API calls (free tier: 500/day).
        skip_known_good_paths: Skip executables in Windows/ProgramFiles paths.

    Returns:
        Summary of enrichment results.
    """
    # Get executables with hashes
    query = """
        MATCH (x:Executable)
        WHERE x.sha1 IS NOT NULL AND x.sha1 <> ''
        OPTIONAL MATCH (x)-[:ENRICHED_BY]->(existing:ThreatIntel)
        WITH x, existing
        WHERE existing IS NULL
        RETURN x.name AS name, x.path AS path, x.sha1 AS sha1
        LIMIT $limit
    """
    executables = run_cypher(query, {"limit": max_lookups * 2})

    if skip_known_good_paths:
        executables = [
            e for e in executables
            if not _is_known_good_path(e.get("path", ""))
        ]

    results = {
        "total_candidates": len(executables),
        "lookups_performed": 0,
        "found": 0,
        "not_found": 0,
        "malicious": 0,
        "errors": 0,
        "details": [],
    }

    for exe in executables[:max_lookups]:
        sha1 = exe.get("sha1", "")
        name = exe.get("name", "")
        path = exe.get("path", "")

        if not sha1:
            continue

        # Rate limit
        if results["lookups_performed"] > 0:
            time.sleep(VT_RATE_LIMIT_SECONDS)

        vt_result = vt_hash_lookup(sha1)
        results["lookups_performed"] += 1

        if vt_result["status"] == "found":
            results["found"] += 1
            detections = vt_result.get("detections", 0)
            if detections > 0:
                results["malicious"] += 1

            # Write ThreatIntel node back to graph
            _write_threat_intel_node(
                run_cypher, path, sha1, vt_result, "virustotal"
            )

            results["details"].append({
                "name": name,
                "sha1": sha1,
                "detections": vt_result.get("detection_rate"),
                "family": vt_result.get("family"),
            })

        elif vt_result["status"] == "not_found":
            results["not_found"] += 1
            # Unknown hash is a signal — write it too
            _write_threat_intel_node(
                run_cypher, path, sha1,
                {"status": "not_found", "message": "Unknown to VT — possible novel malware"},
                "virustotal"
            )
            results["details"].append({
                "name": name,
                "sha1": sha1,
                "detections": "UNKNOWN",
                "family": "not_in_vt",
            })

        elif vt_result["status"] == "rate_limited":
            results["errors"] += 1
            break  # Stop on rate limit

        elif vt_result["status"] == "no_api_key":
            results["errors"] += 1
            results["message"] = "No VT API key configured."
            break

        else:
            results["errors"] += 1

    return results


def enrich_files_by_hash(run_cypher, file_hashes: list[str]) -> dict:
    """Enrich specific file hashes (e.g., from manual investigation).

    Args:
        run_cypher: Cypher execution function.
        file_hashes: List of SHA256/SHA1/MD5 hashes to look up.

    Returns:
        Per-hash results.
    """
    results = []
    for i, h in enumerate(file_hashes):
        if i > 0:
            time.sleep(VT_RATE_LIMIT_SECONDS)

        vt_result = vt_hash_lookup(h)
        results.append({"hash": h, **vt_result})

    return {"lookups": len(results), "results": results}


def _write_threat_intel_node(run_cypher, exe_path: str, sha1: str,
                              vt_data: dict, source: str):
    """Write a ThreatIntel node linked to the Executable via ENRICHED_BY."""
    ts = datetime.now(timezone.utc).isoformat()

    run_cypher("""
        MATCH (x:Executable)
        WHERE x.sha1 = $sha1 OR x.path = $path
        WITH x LIMIT 1
        CREATE (ti:ThreatIntel {
            source: $source,
            status: $status,
            detections: $detections,
            total_engines: $total_engines,
            detection_rate: $detection_rate,
            family: $family,
            sha256: $sha256,
            first_seen_vt: $first_seen,
            timestamp: datetime($ts),
            _origin_tool: 'vt_hash_lookup'
        })
        CREATE (x)-[:ENRICHED_BY {timestamp: datetime($ts)}]->(ti)
    """, {
        "sha1": sha1,
        "path": exe_path,
        "source": source,
        "status": vt_data.get("status", ""),
        "detections": vt_data.get("detections", 0),
        "total_engines": vt_data.get("total_engines", 0),
        "detection_rate": vt_data.get("detection_rate", ""),
        "family": vt_data.get("family", ""),
        "sha256": vt_data.get("sha256", ""),
        "first_seen": str(vt_data.get("first_submission", "")),
        "ts": ts,
    })


def _is_known_good_path(path: str) -> bool:
    """Skip paths that are obviously Windows/vendor binaries."""
    p = path.lower()
    return any(x in p for x in [
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\program files\\",
        "\\program files (x86)\\",
    ])
