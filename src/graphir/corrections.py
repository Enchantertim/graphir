"""Investigation corrections — first-class graph entities for FP/hallucination tracking.

When the agent or an analyst flags a finding as false positive, hallucination,
or otherwise incorrect, the correction is recorded IN the graph as a Correction
node linked to the entities it concerns.

This serves three purposes:
1. Audit trail — judges/analysts can see exactly what was corrected and why
2. Re-generation prevention — the agent can check for existing corrections
   before re-asserting a previously rejected claim
3. Learning signal — corrections are evidence. A graph that contains
   "this was flagged as FP because X" is more trustworthy than one that
   silently drops findings.

Schema:
  (:Correction {
      correction_id,
      type,              -- "false_positive", "hallucination", "retracted", "downgraded"
      reason,            -- human-readable explanation
      original_claim,    -- what was originally asserted
      original_confidence,
      corrected_confidence,
      corrected_by,      -- "agent" or "analyst" or analyst name
      timestamp,
      divergence_data    -- JSON: which predicate failed, why
  })-[:CORRECTS]->(entity)    -- the entity the correction is about
  (correction)-[:DURING]->(investigation)  -- links to investigation session
"""

import json
import uuid
from datetime import datetime, timezone
from enum import Enum


class CorrectionType(str, Enum):
    # Agent-generated (automatic)
    UNSUPPORTED = "unsupported"             # All required predicates absent — claim outside graph
                                             # coverage or evidence not ingested. NOT necessarily
                                             # fabricated — the data may simply not be there.
    DOWNGRADED = "downgraded"               # Mixed predicate failures — partial evidence exists
                                             # but structural verification incomplete.
    # Agent-generated (explicit)
    HALLUCINATION = "hallucination"          # Agent explicitly determines claim was fabricated
                                             # (NOT auto-assigned — requires agent reasoning
                                             # that the claim contradicts available evidence)
    RETRACTED = "retracted"                  # Finding withdrawn after re-examination from source

    # Analyst-generated
    FALSE_POSITIVE = "false_positive"        # Real evidence, wrong interpretation
    SCOPE_ERROR = "scope_error"             # Right evidence, wrong entity/host/timeframe
    ANALYST_OVERRIDE = "analyst_override"    # Human analyst disagrees with agent assessment


def record_correction(run_cypher, correction_type: str, reason: str,
                      original_claim: str, entity_name: str,
                      corrected_by: str = "agent",
                      original_confidence: str = "",
                      corrected_confidence: str = "INSUFFICIENT_EVIDENCE",
                      divergence_data: dict | None = None,
                      investigation_id: str = "",
                      finding_id: str = "") -> dict:
    """Record a correction as a first-class node in the graph.

    Creates a Correction node and links it to the relevant entity via
    a CORRECTS relationship. If an investigation session exists, also
    links via DURING.

    Args:
        run_cypher: Cypher execution function
        correction_type: One of CorrectionType values
        reason: Why this correction was made
        original_claim: What was originally asserted
        entity_name: The entity this correction is about (process, user, host, service)
        corrected_by: Who made the correction ("agent", "analyst", or analyst name)
        original_confidence: What the confidence was before correction
        corrected_confidence: What the confidence is now
        divergence_data: Optional dict with predicate failure details
        investigation_id: Optional investigation session ID

    Returns:
        Dict with correction_id and status
    """
    correction_id = str(uuid.uuid4())[:12]
    ts = datetime.now(timezone.utc).isoformat()

    # Create correction node and link to entity
    query = """
        MERGE (target {name: $entity_name})
        CREATE (c:Correction {
            correction_id: $correction_id,
            type: $correction_type,
            reason: $reason,
            original_claim: $original_claim,
            original_confidence: $original_confidence,
            corrected_confidence: $corrected_confidence,
            corrected_by: $corrected_by,
            timestamp: datetime($ts),
            divergence_data: $divergence_json
        })
        CREATE (c)-[:CORRECTS {timestamp: datetime($ts)}]->(target)
        RETURN c.correction_id AS id
    """

    # Link to entity and store claim context (finding_id, investigation_id)
    # so the correction is about a specific claim-in-context, not just an entity
    # Use exact matching to prevent over-scoping (e.g., 'net.exe' matching 'telnet.exe')
    fallback_query = """
        OPTIONAL MATCH (target)
        WHERE target.name = $entity_name
           OR target.hostname = $entity_name
           OR target.service_name = $entity_name
        WITH target LIMIT 1
        CREATE (c:Correction {
            correction_id: $correction_id,
            type: $correction_type,
            reason: $reason,
            original_claim: $original_claim,
            original_confidence: $original_confidence,
            corrected_confidence: $corrected_confidence,
            corrected_by: $corrected_by,
            timestamp: datetime($ts),
            divergence_data: $divergence_json,
            finding_id: $finding_id,
            investigation_id: $investigation_id
        })
        WITH c, target
        FOREACH (_ IN CASE WHEN target IS NOT NULL THEN [1] ELSE [] END |
            CREATE (c)-[:CORRECTS {timestamp: datetime($ts)}]->(target)
        )
        RETURN c.correction_id AS id
    """

    params = {
        "correction_id": correction_id,
        "correction_type": correction_type,
        "reason": reason,
        "original_claim": original_claim,
        "entity_name": entity_name,
        "original_confidence": original_confidence,
        "corrected_confidence": corrected_confidence,
        "corrected_by": corrected_by,
        "ts": ts,
        "divergence_json": json.dumps(divergence_data or {}, default=str),
        "finding_id": finding_id,
        "investigation_id": investigation_id,
    }

    try:
        result = run_cypher(fallback_query, params)
        return {
            "correction_id": correction_id,
            "status": "recorded",
            "type": correction_type,
            "entity": entity_name,
            "timestamp": ts,
        }
    except Exception as e:
        return {"error": str(e)}


def check_existing_corrections(run_cypher, entity_name: str,
                               claim: str = "") -> list[dict]:
    """Check if an entity or claim already has corrections recorded.

    The agent should call this before re-asserting a claim about an entity
    that was previously flagged. Prevents hallucination re-generation.

    Matching is two-level:
      - entity-level: Correction CORRECTS an entity with this name/hostname/service
      - claim-level: the Correction's original_claim text mentions the entity or
        overlaps the supplied claim — catches corrections whose entity link
        failed to resolve, and corrections about the same assertion phrased
        against a different entity

    Args:
        run_cypher: Cypher execution function
        entity_name: Entity to check (process, user, host, service name)
        claim: Optional claim text — also matches corrections whose
               original_claim contains this text (case-insensitive)
    """
    results = run_cypher("""
        MATCH (c:Correction)
        OPTIONAL MATCH (c)-[:CORRECTS]->(target)
        WITH c, target
        WHERE toLower(target.name) = toLower($name)
           OR toLower(target.hostname) = toLower($name)
           OR toLower(target.service_name) = toLower($name)
           OR toLower(c.original_claim) CONTAINS toLower($name)
           OR ($claim <> '' AND toLower(c.original_claim) CONTAINS toLower($claim))
        RETURN c.correction_id AS id,
               c.type AS type,
               c.reason AS reason,
               c.original_claim AS claim,
               c.corrected_by AS by,
               c.timestamp AS ts,
               CASE WHEN target IS NULL THEN 'claim_text_match'
                    ELSE labels(target)[0] END AS target_type,
               target.name AS target_name
        ORDER BY c.timestamp DESC
        LIMIT 20
    """, {"name": entity_name, "claim": claim})

    return results


def get_correction_summary(run_cypher) -> dict:
    """Get summary of all corrections in the current investigation.

    Useful for the accuracy report and for judges to see
    how the system self-corrected.
    """
    results = run_cypher("""
        MATCH (c:Correction)
        WITH c.type AS type, count(*) AS cnt,
             collect(c.corrected_by)[0..3] AS corrected_by_sample
        RETURN type, cnt, corrected_by_sample
        ORDER BY cnt DESC
    """)

    total = run_cypher("MATCH (c:Correction) RETURN count(*) AS total")
    total_count = total[0]["total"] if total else 0

    agent_corrections = run_cypher("""
        MATCH (c:Correction)
        WHERE c.corrected_by = 'agent'
        RETURN count(*) AS cnt
    """)
    agent_count = agent_corrections[0]["cnt"] if agent_corrections else 0

    return {
        "total_corrections": total_count,
        "by_agent": agent_count,
        "by_analyst": total_count - agent_count,
        "by_type": results,
    }
